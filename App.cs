using DnsServerCore.ApplicationCommon;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemotePolicyBlocking;

public sealed class App : IDnsApplication, IDnsRequestController, IDnsRequestBlockingHandler, IDnsApplicationPreference
{
    private sealed record QuestionDto(string name, string type, string @class);
    private sealed record ClientDto(string ip, int port);
    private sealed record DnsDto(
        ushort identifier,
        bool is_response,
        string opcode,
        bool authoritative_answer,
        bool truncation,
        bool recursion_desired,
        bool recursion_available,
        bool authentic_data,
        bool checking_disabled,
        string rcode,
        bool has_edns,
        int question_count,
        int answer_count,
        int authority_count,
        int additional_count,
        string wire_base64,
        IReadOnlyList<QuestionDto> questions
    );
    private sealed record DecisionRequestDto(string? server_id, string? protocol, ClientDto client, DnsDto dns);
    private sealed class DecisionResponseDto
    {
        public bool block { get; set; }
        public string? reason { get; set; }
        public string? matched_scope { get; set; }
        public string? matched_list { get; set; }
        public string? matched_domain { get; set; }
        public string? response_mode { get; set; }
    }
    private sealed record CachedDecision(DecisionResponseDto Decision, DateTime ExpiresUtc);

    private readonly ConcurrentDictionary<string, CachedDecision> _decisions = new();
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    private IDnsServer? _dnsServer;
    private HttpClient _httpClient = new();
    private X509Certificate2? _tlsCustomCa;
    private Uri _endpoint = new("http://127.0.0.1:8080/api/v1/decision");
    private string _apiKey = "";
    private bool _tlsVerifyServerCertificate = true;
    private string? _tlsCaCertificatePath;
    private string? _serverId;
    private int _timeoutMs = 250;
    private string _failMode = "open";
    private uint _blockAnswerTtl = 30;
    private bool _bypassBuiltInBlockingOnAllow = true;
    private bool _diagnosticLogging = false;
    private int _loggedSuccess;
    private byte _preference = 25;
    private DnsSOARecordData? _soaRecord;

    public string Description => "Uses a remote HTTP/HTTPS policy service to make per-client DNS blocking decisions.";
    public byte Preference => _preference;

    public void Dispose()
    {
        _httpClient.Dispose();
        _tlsCustomCa?.Dispose();
        _decisions.Clear();
    }

    public Task InitializeAsync(IDnsServer dnsServer, string? config)
    {
        _dnsServer = dnsServer;
        if (string.IsNullOrWhiteSpace(config))
            throw new InvalidOperationException("dnsApp.config is required.");

        using JsonDocument doc = JsonDocument.Parse(config, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip });
        JsonElement root = doc.RootElement;

        _preference = ReadByte(root, "appPreference", 25);
        _endpoint = new Uri(ReadString(root, "endpoint", "http://127.0.0.1:8080/api/v1/decision"));
        if (_endpoint.Scheme != Uri.UriSchemeHttp && _endpoint.Scheme != Uri.UriSchemeHttps)
            throw new FormatException("endpoint must use http:// or https://.");

        _apiKey = ReadString(root, "apiKey", "");
        _tlsVerifyServerCertificate = ReadBool(root, "tlsVerifyServerCertificate", true);
        _tlsCaCertificatePath = ReadNullableString(root, "tlsCaCertificatePath");
        if (string.IsNullOrWhiteSpace(_tlsCaCertificatePath))
            _tlsCaCertificatePath = null;
        else
            _tlsCaCertificatePath = _tlsCaCertificatePath.Trim();

        _serverId = ReadNullableString(root, "serverId");
        _timeoutMs = Math.Clamp(ReadInt(root, "timeoutMs", 250), 25, 10000);
        _failMode = ReadString(root, "failMode", "open").ToLowerInvariant();
        if (_failMode is not ("open" or "closed"))
            throw new FormatException("failMode must be 'open' or 'closed'.");
        _blockAnswerTtl = (uint)Math.Clamp(ReadInt(root, "blockAnswerTtl", 30), 0, 86400);
        _bypassBuiltInBlockingOnAllow = ReadBool(root, "bypassBuiltInBlockingOnAllow", true);
        _diagnosticLogging = ReadBool(root, "diagnosticLogging", false);
        _loggedSuccess = 0;

        _httpClient.Dispose();
        _tlsCustomCa?.Dispose();
        _tlsCustomCa = null;

        if (_endpoint.Scheme == Uri.UriSchemeHttps && _tlsCaCertificatePath is not null)
        {
            if (!File.Exists(_tlsCaCertificatePath))
                throw new FileNotFoundException("The configured TLS CA certificate file was not found.", _tlsCaCertificatePath);

            _tlsCustomCa = X509CertificateLoader.LoadCertificateFromFile(_tlsCaCertificatePath);
        }

        HttpClientHandler httpHandler = new();
        if (_endpoint.Scheme == Uri.UriSchemeHttps)
        {
            if (!_tlsVerifyServerCertificate)
                httpHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            else if (_tlsCustomCa is not null)
                httpHandler.ServerCertificateCustomValidationCallback = ValidateServerCertificate;
        }

        _httpClient = new HttpClient(httpHandler)
        {
            Timeout = TimeSpan.FromMilliseconds(_timeoutMs)
        };
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrEmpty(_apiKey))
            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", _apiKey);

        _soaRecord = new DnsSOARecordData(
            dnsServer.ServerDomain,
            dnsServer.ResponsiblePerson.Address,
            1,
            14400,
            3600,
            604800,
            _blockAnswerTtl
        );

        _decisions.Clear();

        if (_endpoint.Scheme == Uri.UriSchemeHttps && !_tlsVerifyServerCertificate)
            _dnsServer.WriteLog("WARNING: Remote Policy Blocking TLS server-certificate verification is DISABLED. This should only be used for controlled testing.");

        _dnsServer.WriteLog($"Remote Policy Blocking app initialized. Endpoint={_endpoint}; timeoutMs={_timeoutMs}; failMode={_failMode}; diagnosticLogging={_diagnosticLogging}; tlsVerifyServerCertificate={_tlsVerifyServerCertificate}; customTlsCa={_tlsCustomCa is not null}.");
        return ProbePolicyServerAsync();
    }

    public async Task<DnsRequestControllerAction> GetRequestActionAsync(
        DnsDatagram request,
        IPEndPoint remoteEP,
        DnsTransportProtocol protocol)
    {
        if (_diagnosticLogging)
        {
            string q = request.Question.Count > 0
                ? string.Join(", ", request.Question.Select(x => $"{x.Name}/{x.Type}"))
                : "<no-question>";
            _dnsServer?.WriteLog($"Remote Policy Blocking intercepted query from {remoteEP} via {protocol}: {q}");
        }

        DecisionResponseDto decision = await QueryPolicyAsync(request, remoteEP, protocol.ToString());
        PutDecision(request, remoteEP, decision);

        // The request controller is used to capture protocol information before the DNS core runs.
        // Actual DNS blocking is performed by IDnsRequestBlockingHandler so we can synthesize
        // NXDOMAIN/NODATA/zero-address responses rather than being limited to REFUSED/drop.
        return DnsRequestControllerAction.Allow;
    }

    public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
    {
        if (!_bypassBuiltInBlockingOnAllow)
            return Task.FromResult(false);

        if (TryGetDecision(request, remoteEP, consume: false, out DecisionResponseDto? decision) && decision is not null)
            return Task.FromResult(!decision.block);

        return Task.FromResult(false);
    }

    public async Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
    {
        // Let Technitium handle malformed/empty-question packets normally.
        if (request.Question.Count == 0)
            return null;

        DecisionResponseDto decision;
        if (!TryGetDecision(request, remoteEP, consume: true, out DecisionResponseDto? cached) || cached is null)
            decision = await QueryPolicyAsync(request, remoteEP, null);
        else
            decision = cached;

        if (!decision.block)
            return null;

        return BuildBlockedResponse(request, decision);
    }

    private bool ValidateServerCertificate(
        HttpRequestMessage _,
        X509Certificate2? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
            return true;

        if (certificate is null || _tlsCustomCa is null)
            return false;

        if ((sslPolicyErrors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0)
            return false;

        using X509Chain customChain = new();
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(_tlsCustomCa);
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        if (chain is not null)
        {
            foreach (X509ChainElement element in chain.ChainElements.Skip(1))
            {
                if (!string.Equals(element.Certificate.Thumbprint, _tlsCustomCa.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    customChain.ChainPolicy.ExtraStore.Add(element.Certificate);
            }
        }

        return customChain.Build(certificate);
    }

    private async Task<DecisionResponseDto> QueryPolicyAsync(DnsDatagram request, IPEndPoint remoteEP, string? protocol)
    {
        try
        {
            List<QuestionDto> questions = request.Question
                .Select(q => new QuestionDto(q.Name, q.Type.ToString(), q.Class.ToString()))
                .ToList();

            using MemoryStream wire = new();
            request.WriteTo(wire);

            DnsDto dns = new(
                request.Identifier,
                request.IsResponse,
                request.OPCODE.ToString(),
                request.AuthoritativeAnswer,
                request.Truncation,
                request.RecursionDesired,
                request.RecursionAvailable,
                request.AuthenticData,
                request.CheckingDisabled,
                request.RCODE.ToString(),
                request.EDNS is not null,
                request.Question.Count,
                request.Answer.Count,
                request.Authority.Count,
                request.Additional.Count,
                Convert.ToBase64String(wire.ToArray()),
                questions
            );

            DecisionRequestDto payload = new(
                _serverId,
                protocol,
                new ClientDto(remoteEP.Address.ToString(), remoteEP.Port),
                dns
            );

            string json = JsonSerializer.Serialize(payload, _jsonOptions);
            using HttpRequestMessage httpRequest = new(HttpMethod.Post, _endpoint)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
            using HttpResponseMessage response = await _httpClient.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead);
            string body = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                string compactBody = body.Length > 512 ? body[..512] + "..." : body;
                throw new HttpRequestException($"Policy server returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}: {compactBody}", null, response.StatusCode);
            }

            DecisionResponseDto? decision = JsonSerializer.Deserialize<DecisionResponseDto>(body, _jsonOptions);
            if (decision is null)
                throw new InvalidDataException("Policy server returned an empty decision.");

            if (_diagnosticLogging)
                _dnsServer?.WriteLog($"Remote Policy Blocking decision for {remoteEP.Address}: block={decision.block}; reason={decision.reason ?? "<none>"}; scope={decision.matched_scope ?? "<none>"}; list={decision.matched_list ?? "<none>"}.");
            else if (Interlocked.Exchange(ref _loggedSuccess, 1) == 0)
                _dnsServer?.WriteLog("Remote Policy Blocking successfully received its first decision from the policy server.");

            return decision;
        }
        catch (Exception ex)
        {
            _dnsServer?.WriteLog("Remote Policy Blocking app policy lookup failed: " + ex.Message);
            return new DecisionResponseDto
            {
                block = _failMode == "closed",
                reason = _failMode == "closed" ? "policy_unavailable_fail_closed" : "policy_unavailable_fail_open",
                response_mode = "refused"
            };
        }
    }


    private async Task ProbePolicyServerAsync()
    {
        if (_dnsServer is null)
            return;

        try
        {
            Uri pingUri = new(_endpoint, "ping");
            using HttpRequestMessage request = new(HttpMethod.Get, pingUri);
            using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            string body = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                _dnsServer.WriteLog($"Remote Policy Blocking connectivity probe succeeded: {pingUri}");
                return;
            }

            string compactBody = body.Length > 512 ? body[..512] + "..." : body;
            _dnsServer.WriteLog($"Remote Policy Blocking connectivity probe FAILED: {pingUri} returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}: {compactBody}");
        }
        catch (Exception ex)
        {
            _dnsServer.WriteLog($"Remote Policy Blocking connectivity probe FAILED for {_endpoint}. Check endpoint address, Docker networking/firewall, TLS certificate trust/custom CA settings, and policy service availability.", ex);
        }
    }

    private DnsDatagram BuildBlockedResponse(DnsDatagram request, DecisionResponseDto decision)
    {
        if (_dnsServer is null || _soaRecord is null)
            throw new InvalidOperationException("Application is not initialized.");

        DnsQuestionRecord question = request.Question[0];
        string mode = (decision.response_mode ?? "nxdomain").ToLowerInvariant();
        IReadOnlyList<DnsResourceRecord>? answer = null;
        IReadOnlyList<DnsResourceRecord>? authority = null;
        DnsResponseCode rcode;

        switch (mode)
        {
            case "refused":
                rcode = DnsResponseCode.Refused;
                break;

            case "nodata":
                rcode = DnsResponseCode.NoError;
                authority = BuildSoaAuthority(question, decision.matched_domain);
                break;

            case "zero":
                rcode = DnsResponseCode.NoError;
                if (question.Type == DnsResourceRecordType.A)
                {
                    answer = new[]
                    {
                        new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _blockAnswerTtl,
                            new DnsARecordData(IPAddress.Any))
                    };
                }
                else if (question.Type == DnsResourceRecordType.AAAA)
                {
                    answer = new[]
                    {
                        new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, _blockAnswerTtl,
                            new DnsAAAARecordData(IPAddress.IPv6Any))
                    };
                }
                else
                {
                    authority = BuildSoaAuthority(question, decision.matched_domain);
                }
                break;

            case "nxdomain":
            default:
                rcode = DnsResponseCode.NxDomain;
                authority = BuildSoaAuthority(question, decision.matched_domain);
                break;
        }

        return new DnsDatagram(
            request.Identifier,
            true,
            request.OPCODE,
            false,
            false,
            request.RecursionDesired,
            false,
            false,
            request.CheckingDisabled,
            rcode,
            request.Question,
            answer,
            authority,
            null,
            request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize,
            EDnsHeaderFlags.None,
            null
        );
    }

    private IReadOnlyList<DnsResourceRecord> BuildSoaAuthority(DnsQuestionRecord question, string? matchedDomain)
    {
        string owner = string.IsNullOrWhiteSpace(matchedDomain) ? question.Name : matchedDomain.TrimEnd('.');
        return new[]
        {
            new DnsResourceRecord(owner, DnsResourceRecordType.SOA, question.Class, _blockAnswerTtl, _soaRecord!)
        };
    }

    private string MakeKey(DnsDatagram request, IPEndPoint remoteEP)
    {
        StringBuilder sb = new();
        sb.Append(remoteEP.Address).Append('|').Append(remoteEP.Port).Append('|').Append(request.Identifier);
        foreach (DnsQuestionRecord q in request.Question)
            sb.Append('|').Append(q.Name.ToLowerInvariant()).Append('|').Append(q.Type).Append('|').Append(q.Class);
        return sb.ToString();
    }

    private void PutDecision(DnsDatagram request, IPEndPoint remoteEP, DecisionResponseDto decision)
    {
        CleanupExpired();
        _decisions[MakeKey(request, remoteEP)] = new CachedDecision(decision, DateTime.UtcNow.AddSeconds(5));
    }

    private bool TryGetDecision(DnsDatagram request, IPEndPoint remoteEP, bool consume, out DecisionResponseDto? decision)
    {
        string key = MakeKey(request, remoteEP);
        if (_decisions.TryGetValue(key, out CachedDecision? cached))
        {
            if (cached.ExpiresUtc > DateTime.UtcNow)
            {
                decision = cached.Decision;
                if (consume)
                    _decisions.TryRemove(key, out _);
                return true;
            }
            _decisions.TryRemove(key, out _);
        }
        decision = null;
        return false;
    }

    private void CleanupExpired()
    {
        if (_decisions.Count < 4096)
            return;
        DateTime now = DateTime.UtcNow;
        foreach ((string key, CachedDecision value) in _decisions)
        {
            if (value.ExpiresUtc <= now)
                _decisions.TryRemove(key, out _);
        }
    }

    private static string ReadString(JsonElement root, string name, string fallback) =>
        root.TryGetProperty(name, out JsonElement e) && e.ValueKind == JsonValueKind.String ? e.GetString() ?? fallback : fallback;

    private static string? ReadNullableString(JsonElement root, string name) =>
        root.TryGetProperty(name, out JsonElement e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;

    private static int ReadInt(JsonElement root, string name, int fallback) =>
        root.TryGetProperty(name, out JsonElement e) && e.TryGetInt32(out int value) ? value : fallback;

    private static byte ReadByte(JsonElement root, string name, byte fallback) =>
        root.TryGetProperty(name, out JsonElement e) && e.TryGetByte(out byte value) ? value : fallback;

    private static bool ReadBool(JsonElement root, string name, bool fallback) =>
        root.TryGetProperty(name, out JsonElement e) && e.ValueKind is JsonValueKind.True or JsonValueKind.False ? e.GetBoolean() : fallback;
}

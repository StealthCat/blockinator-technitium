using DnsServerCore.ApplicationCommon;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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
        // Nullable so that a reply without an explicit decision is rejected instead of
        // silently deserializing as "allow".
        public bool? block { get; set; }
        public string? reason { get; set; }
        public string? matched_scope { get; set; }
        public string? matched_list { get; set; }
        public string? matched_domain { get; set; }
        public string? response_mode { get; set; }

        // Set for synthesized fail-open/fail-closed decisions; never read from JSON.
        [JsonIgnore]
        public bool PolicyUnavailable { get; init; }

        [JsonIgnore]
        public bool IsBlocked => block == true;
    }
    private sealed record CachedDecision(DecisionResponseDto Decision, DateTime ExpiresUtc);

    private const int MaxDecisionResponseBytes = 16384;
    private const int MaxLoggedBodyChars = 512;
    private static readonly TimeSpan DecisionHandoffLifetime = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan FailureLogInterval = TimeSpan.FromSeconds(60);
    private const string PlaceholderApiKey = "change-this-long-random-api-key";

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
    private long _lastCleanupTicks;
    private long _lastFailureLogTicks;
    private long _suppressedFailures;
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

    private static string Truncate(string text) =>
        text.Length > MaxLoggedBodyChars ? text[..MaxLoggedBodyChars] + "..." : text;

    public Task InitializeAsync(IDnsServer dnsServer, string? config)
    {
        _dnsServer = dnsServer;
        if (string.IsNullOrWhiteSpace(config))
            throw new InvalidOperationException("dnsApp.config is required.");

        using JsonDocument doc = JsonDocument.Parse(config, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip });
        JsonElement root = doc.RootElement;

        _preference = ReadByte(root, "appPreference", 25);
        Uri endpoint = new(ReadString(root, "endpoint", "http://127.0.0.1:8080/api/v1/decision"), UriKind.Absolute);
        if (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps)
            throw new FormatException("endpoint must use http:// or https://.");
        // Credentials embedded in the URL would be written to the Technitium log below.
        if (!string.IsNullOrEmpty(endpoint.UserInfo))
            throw new FormatException("endpoint must not contain credentials; use apiKey instead.");
        _endpoint = endpoint;

        _apiKey = ReadString(root, "apiKey", "").Trim();
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
        Interlocked.Exchange(ref _lastFailureLogTicks, 0);
        Interlocked.Exchange(ref _suppressedFailures, 0);

        X509Certificate2? customCa = null;
        if (_endpoint.Scheme == Uri.UriSchemeHttps && _tlsCaCertificatePath is not null)
        {
            if (!File.Exists(_tlsCaCertificatePath))
                throw new FileNotFoundException("The configured TLS CA certificate file was not found.", _tlsCaCertificatePath);

            customCa = X509CertificateLoader.LoadCertificateFromFile(_tlsCaCertificatePath);
        }

        HttpClientHandler httpHandler = new()
        {
            // Never follow redirects: the X-Api-Key header would be forwarded to the new location.
            AllowAutoRedirect = false,
            // Ignore ambient HTTP(S)_PROXY settings so the key only goes to the configured endpoint.
            UseProxy = false
        };
        if (_endpoint.Scheme == Uri.UriSchemeHttps)
        {
            if (!_tlsVerifyServerCertificate)
                httpHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            else if (customCa is not null)
                httpHandler.ServerCertificateCustomValidationCallback = (_, certificate, chain, errors) =>
                    ValidateServerCertificate(customCa, certificate, chain, errors);
        }

        HttpClient httpClient = new(httpHandler)
        {
            // Per-request deadlines (including the response body) are enforced with a
            // CancellationToken in SendPolicyRequestAsync; this is only a backstop.
            Timeout = TimeSpan.FromMilliseconds(_timeoutMs * 2)
        };
        httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrEmpty(_apiKey))
            httpClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", _apiKey);

        // Swap in the new client first so queries in flight during a configuration reload
        // finish on the old client instead of failing with ObjectDisposedException.
        HttpClient oldClient = Interlocked.Exchange(ref _httpClient, httpClient);
        X509Certificate2? oldCa = Interlocked.Exchange(ref _tlsCustomCa, customCa);
        // 30 s exceeds the longest possible request lifetime (2 x the 10 s maximum timeout).
        _ = Task.Delay(TimeSpan.FromSeconds(30)).ContinueWith(_ =>
        {
            oldClient.Dispose();
            oldCa?.Dispose();
        }, TaskScheduler.Default);

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
        if (_apiKey.Length == 0 || _apiKey == PlaceholderApiKey)
            _dnsServer.WriteLog("WARNING: Remote Policy Blocking apiKey is empty or still set to the example value; Blockinator will reject policy requests until a valid key is configured.");

        _dnsServer.WriteLog($"Remote Policy Blocking app initialized. Endpoint={_endpoint}; timeoutMs={_timeoutMs}; failMode={_failMode}; diagnosticLogging={_diagnosticLogging}; tlsVerifyServerCertificate={_tlsVerifyServerCertificate}; customTlsCa={_tlsCustomCa is not null}.");
        return ProbePolicyServerAsync();
    }

    public async Task<DnsRequestControllerAction> GetRequestActionAsync(
        DnsDatagram request,
        IPEndPoint remoteEP,
        DnsTransportProtocol protocol)
    {
        // Malformed/empty-question packets are handled by Technitium itself and never reach
        // the blocking stage, so there is nothing for the policy server to decide.
        if (request.Question.Count == 0)
            return DnsRequestControllerAction.Allow;

        if (_diagnosticLogging)
        {
            string q = string.Join(", ", request.Question.Select(x => $"{x.Name}/{x.Type}"));
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

        if (!TryGetDecision(request, remoteEP, consume: false, out DecisionResponseDto? decision) || decision is null)
            return Task.FromResult(false);

        // Only an explicit ALLOW from Blockinator may bypass built-in blocking. A fail-open
        // fallback must not disable Technitium's own block lists during a policy outage.
        if (decision.IsBlocked || decision.PolicyUnavailable)
            return Task.FromResult(false);

        // Technitium skips the blocking stage for allowed requests, so release the handoff now.
        TryGetDecision(request, remoteEP, consume: true, out _);
        return Task.FromResult(true);
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

        if (!decision.IsBlocked)
            return null;

        return BuildBlockedResponse(request, decision);
    }

    private static bool ValidateServerCertificate(
        X509Certificate2 customCa,
        X509Certificate2? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
            return true;

        if (certificate is null)
            return false;

        if ((sslPolicyErrors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0)
            return false;

        using X509Chain customChain = new();
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(customCa);
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        if (chain is not null)
        {
            foreach (X509ChainElement element in chain.ChainElements.Skip(1))
            {
                if (!string.Equals(element.Certificate.Thumbprint, customCa.Thumbprint, StringComparison.OrdinalIgnoreCase))
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
            (HttpStatusCode status, string? reasonPhrase, string body) = await SendPolicyRequestAsync(httpRequest);
            if ((int)status < 200 || (int)status > 299)
                throw new HttpRequestException($"Policy server returned HTTP {(int)status} {reasonPhrase}: {Truncate(body)}", null, status);

            DecisionResponseDto? decision = JsonSerializer.Deserialize<DecisionResponseDto>(body, _jsonOptions);
            if (decision is null)
                throw new InvalidDataException("Policy server returned an empty decision.");
            if (decision.block is null)
                throw new InvalidDataException("Policy server decision is missing the boolean 'block' field.");

            if (_diagnosticLogging)
                _dnsServer?.WriteLog($"Remote Policy Blocking decision for {remoteEP.Address}: block={decision.IsBlocked}; reason={decision.reason ?? "<none>"}; scope={decision.matched_scope ?? "<none>"}; list={decision.matched_list ?? "<none>"}.");
            else if (Interlocked.Exchange(ref _loggedSuccess, 1) == 0)
                _dnsServer?.WriteLog("Remote Policy Blocking successfully received its first decision from the policy server.");

            return decision;
        }
        catch (Exception ex)
        {
            LogPolicyFailure(ex);
            return new DecisionResponseDto
            {
                block = _failMode == "closed",
                reason = _failMode == "closed" ? "policy_unavailable_fail_closed" : "policy_unavailable_fail_open",
                response_mode = "refused",
                PolicyUnavailable = true
            };
        }
    }

    /// <summary>
    /// Sends a policy request with a single deadline covering connection, headers and the
    /// response body, and reads at most <see cref="MaxDecisionResponseBytes"/> of the body.
    /// </summary>
    private async Task<(HttpStatusCode Status, string? ReasonPhrase, string Body)> SendPolicyRequestAsync(HttpRequestMessage request)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromMilliseconds(_timeoutMs));
        try
        {
            using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.Content.Headers.ContentLength > MaxDecisionResponseBytes && response.IsSuccessStatusCode)
                throw new InvalidDataException($"Policy server response exceeds {MaxDecisionResponseBytes} bytes.");

            await using Stream stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            byte[] buffer = new byte[MaxDecisionResponseBytes + 1];
            int length = 0;
            int read;
            while (length < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(length), timeout.Token)) > 0)
                length += read;

            if (length > MaxDecisionResponseBytes && response.IsSuccessStatusCode)
                throw new InvalidDataException($"Policy server response exceeds {MaxDecisionResponseBytes} bytes.");

            string body = Encoding.UTF8.GetString(buffer, 0, Math.Min(length, MaxDecisionResponseBytes));
            return (response.StatusCode, response.ReasonPhrase, body);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            throw new TimeoutException($"Policy server did not respond within {_timeoutMs} ms.");
        }
    }

    /// <summary>
    /// Logs policy lookup failures at most once per minute so an outage does not flood the
    /// Technitium log on a busy resolver.
    /// </summary>
    private void LogPolicyFailure(Exception ex)
    {
        long now = DateTime.UtcNow.Ticks;
        long last = Interlocked.Read(ref _lastFailureLogTicks);
        if ((last != 0 && now - last < FailureLogInterval.Ticks) ||
            Interlocked.CompareExchange(ref _lastFailureLogTicks, now, last) != last)
        {
            Interlocked.Increment(ref _suppressedFailures);
            return;
        }

        long suppressed = Interlocked.Exchange(ref _suppressedFailures, 0);
        string suffix = suppressed > 0 ? $" ({suppressed} similar failures suppressed in the last minute)" : "";
        _dnsServer?.WriteLog($"Remote Policy Blocking app policy lookup failed; applying failMode={_failMode}: {ex.Message}{suffix}");
    }


    private async Task ProbePolicyServerAsync()
    {
        if (_dnsServer is null)
            return;

        try
        {
            Uri pingUri = new(_endpoint, "ping");
            using HttpRequestMessage request = new(HttpMethod.Get, pingUri);
            (HttpStatusCode status, string? reasonPhrase, string body) = await SendPolicyRequestAsync(request);

            if ((int)status >= 200 && (int)status <= 299)
            {
                _dnsServer.WriteLog($"Remote Policy Blocking connectivity probe succeeded: {pingUri}");
                return;
            }

            _dnsServer.WriteLog($"Remote Policy Blocking connectivity probe FAILED: {pingUri} returned HTTP {(int)status} {reasonPhrase}: {Truncate(body)}");
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
            true, // the blocking stage only runs for clients that are allowed recursion
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
        return new[]
        {
            new DnsResourceRecord(SoaOwner(question.Name, matchedDomain), DnsResourceRecordType.SOA, question.Class, _blockAnswerTtl, _soaRecord!)
        };
    }

    /// <summary>
    /// Uses Blockinator's matched domain as the SOA owner only when it is the queried name or
    /// one of its parent domains. Anything else (wildcards, regex rules, other domains) would
    /// either be rejected by DnsResourceRecord, turning the block into a silent allow, or
    /// produce an out-of-bailiwick authority record.
    /// </summary>
    private static string SoaOwner(string questionName, string? matchedDomain)
    {
        if (string.IsNullOrWhiteSpace(matchedDomain))
            return questionName;

        string candidate = matchedDomain.Trim().TrimEnd('.');
        string name = questionName.TrimEnd('.');
        if (candidate.Length == 0 || !DnsClient.IsDomainNameValid(candidate))
            return questionName;

        if (name.Equals(candidate, StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith("." + candidate, StringComparison.OrdinalIgnoreCase))
            return candidate;

        return questionName;
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
        _decisions[MakeKey(request, remoteEP)] = new CachedDecision(decision, DateTime.UtcNow.Add(DecisionHandoffLifetime));
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
        // Entries orphaned by requests that never reach the blocking stage (recursion denied,
        // allowed by another handler, ...) are swept here. Throttle the O(n) sweep so a busy
        // resolver does not rescan the whole dictionary on every query.
        if (_decisions.Count < 4096)
            return;
        DateTime now = DateTime.UtcNow;
        long last = Interlocked.Read(ref _lastCleanupTicks);
        if (now.Ticks - last < CleanupInterval.Ticks ||
            Interlocked.CompareExchange(ref _lastCleanupTicks, now.Ticks, last) != last)
            return;
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

    // TryGetInt32/TryGetByte throw InvalidOperationException for non-number values, so the
    // value kind must be checked first (e.g. "timeoutMs": "250" falls back to the default).
    private static int ReadInt(JsonElement root, string name, int fallback) =>
        root.TryGetProperty(name, out JsonElement e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out int value) ? value : fallback;

    private static byte ReadByte(JsonElement root, string name, byte fallback) =>
        root.TryGetProperty(name, out JsonElement e) && e.ValueKind == JsonValueKind.Number && e.TryGetByte(out byte value) ? value : fallback;

    private static bool ReadBool(JsonElement root, string name, bool fallback) =>
        root.TryGetProperty(name, out JsonElement e) && e.ValueKind is JsonValueKind.True or JsonValueKind.False ? e.GetBoolean() : fallback;
}

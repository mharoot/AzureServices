using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WEBNAME.EmployeeSync;

public static class EmployeeQuery
{
    /// <summary>
    /// Incremental pull ordered by (SystemModstamp, Id).
    /// Uses ">=" on purpose: several rows can share one timestamp across a batch boundary, and ">" would
    /// skip the ones not yet processed. The boundary row is simply re-sent, which is harmless because the
    /// sink upserts by Id (at-least-once + idempotent writes = effectively-once results).
    /// </summary>
    public static string Build(DateTimeOffset? since)
    {
        var where = since == null ? "" : $" WHERE SystemModstamp >= {Format(since.Value)}";
        return "SELECT Id, Name, Email__c, Department__c, SystemModstamp FROM Employee__c" +
               where + " ORDER BY SystemModstamp ASC, Id ASC";
    }

    /// <summary>SOQL datetime literal (unquoted, UTC).</summary>
    public static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
}

public static class EmployeeMapper
{
    // Salesforce returns offsets as "+0000" (no colon), which System.Text.Json / DateTimeOffset reject.
    private static readonly Regex OffsetWithoutColon = new(@"([+-]\d{2})(\d{2})$", RegexOptions.Compiled);

    /// <summary>Validates and maps one Salesforce record. Bad rows are reported, never thrown, so one bad row cannot block the feed.</summary>
    public static bool TryMap(JsonElement record, out Employee employee, out string error)
    {
        employee = null;

        var id = Read(record, "Id");
        var name = Read(record, "Name");
        var email = Read(record, "Email__c");
        var department = Read(record, "Department__c");

        if (string.IsNullOrWhiteSpace(id)) { error = "Missing Id."; return false; }
        if (string.IsNullOrWhiteSpace(name)) { error = $"Record {id}: missing Name."; return false; }
        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@')) { error = $"Record {id}: invalid email."; return false; }
        if (!TryParseTimestamp(Read(record, "SystemModstamp"), out var modified)) { error = $"Record {id}: invalid SystemModstamp."; return false; }

        employee = new Employee(id, name.Trim(), email.Trim(), department?.Trim(), modified);
        error = null;
        return true;
    }

    public static bool TryParseTimestamp(string value, out DateTimeOffset result)
    {
        result = default;
        if (string.IsNullOrWhiteSpace(value)) return false;

        var normalised = OffsetWithoutColon.Replace(value, "$1:$2");
        if (!DateTimeOffset.TryParse(normalised, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
            return false;

        result = parsed.ToUniversalTime();
        return true;
    }

    private static string Read(JsonElement record, string field) =>
        record.TryGetProperty(field, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

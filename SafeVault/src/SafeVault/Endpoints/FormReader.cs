namespace SafeVault.Endpoints;

internal static class FormReader
{
    /// <summary>
    /// Reads the posted form, or returns null if the body isn't a valid form: the wrong content
    /// type, or characters ASP.NET Core refuses to decode (such as null bytes, "%00"). Callers
    /// answer 400 Bad Request instead of crashing with a 500 error.
    /// </summary>
    public static async Task<IFormCollection?> TryReadFormAsync(HttpRequest request)
    {
        if (!request.HasFormContentType)
            return null;

        try
        {
            return await request.ReadFormAsync();
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }
}

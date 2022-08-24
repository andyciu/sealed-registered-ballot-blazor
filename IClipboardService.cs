namespace sealed_registered_ballot_blazor;
public interface IClipboardService
{
    Task CopyToClipboard(string text);
}
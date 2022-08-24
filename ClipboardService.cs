using Microsoft.JSInterop;
namespace sealed_registered_ballot_blazor;
public class ClipboardService : IClipboardService
{
    private readonly IJSRuntime _jsInterop;

    public ClipboardService(IJSRuntime jsInterop)
    {
        _jsInterop = jsInterop;
    }

    public async Task CopyToClipboard(string text)
    {
        await _jsInterop.InvokeVoidAsync("navigator.clipboard.writeText", text);
    }
}

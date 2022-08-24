using Microsoft.JSInterop;
namespace sealed_registered_ballot_blazor;
public class CryptographyService_JS : ICryptographyService
{
    private readonly IJSRuntime _jsInterop;

    public CryptographyService_JS(IJSRuntime jsInterop)
    {
        _jsInterop = jsInterop;
    }
    class InvokeReturnData_generateKey
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }
    public async Task<(string rsaPublicstr, string rsaPrivatestr)> GetRSAKeyPair()
    {
        var result = await _jsInterop.InvokeAsync<InvokeReturnData_generateKey>("SRBB_generateKey_RSA");
        return (result.PublicKey, result.PrivateKey);
    }

    public string CreateVoterString()
    {
        return "A:1=B:2=C:3=D:4";
    }

    public async Task<string> EncryptVote(string votestr, string ballotPublickey, string voterkey)
    {
        var result1 = await _jsInterop.InvokeAsync<byte[]>("SRBB_encrypt_RSA", ballotPublickey, votestr);
        var result1str = Convert.ToBase64String(result1);

        var result2 = await _jsInterop.InvokeAsync<byte[]>("SRBB_encrypt_AES", voterkey, result1str);
        var result2str = Convert.ToBase64String(result2);

        return result2str;
    }

    public async Task<string> GetAESKey()
    {
        return await _jsInterop.InvokeAsync<string>("SRBB_generateKey_AES");
    }
}


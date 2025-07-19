using Microsoft.JSInterop;

namespace sealed_registered_ballot_blazor;
public class CryptographyService_JS(IJSRuntime jsInterop) : ICryptographyService
{
    class InvokeReturnData_generateKey
    {
        public string PublicKey { get; set; } = "";
        public string PrivateKey { get; set; } = "";
    }
    public async Task<(string rsaPublicstr, string rsaPrivatestr)> GetRSAKeyPair()
    {
        var result = await jsInterop.InvokeAsync<InvokeReturnData_generateKey>("SRBB_generateKey_RSA");
        return (result.PublicKey, result.PrivateKey);
    }

    public async Task<string> GetAESKey()
    {
        return await jsInterop.InvokeAsync<string>("SRBB_generateKey_AES");
    }

    public Dictionary<string, int> CreateVoterOptionDict(int optCount)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        Random random = new();
        Dictionary<string, int> result = [];
        int totalnum = optCount > 26 ? 26 : optCount;
        bool[] optvaluesflag = new bool[totalnum];

        for (int i = 0; i < totalnum; i++)
        {
            int tmprngnum = random.Next(totalnum);
            if (!optvaluesflag[tmprngnum])
            {
                optvaluesflag[tmprngnum] = true;
            }
            else
            {
                i--;
                continue;
            }

            result.Add(chars[i].ToString(), tmprngnum + 1);
        }

        return result;
    }

    public Dictionary<string, int> CreateVoterOptionDict(string votestr)
    {
        Dictionary<string, int> result = [];
        string[] tmpOptArr = votestr.Split('=');
        foreach (string key in tmpOptArr)
        {
            string[] tmpvalues = key.Split(':');
            result.Add(tmpvalues[0], Convert.ToInt32(tmpvalues[1]));
        }

        return result;
    }

    public string ConvertVoterOptionDictToString(Dictionary<string, int> opts)
    {
        string result = "";
        foreach (KeyValuePair<string, int> opt in opts)
        {
            string key = opt.Key;
            int val = opt.Value;

            result = result + key + ":" + val + "=";
        }
        return result[..^1];
    }

    public async Task<string> EncryptVote(string votestr, string ballotPublickey, string voterkey)
    {
        var result1 = await jsInterop.InvokeAsync<byte[]>("SRBB_encrypt_RSA", ballotPublickey, votestr);
        var result1str = Convert.ToBase64String(result1);

        var result2 = await jsInterop.InvokeAsync<string>("SRBB_encrypt_AES", voterkey, result1str);

        return result2;
    }

    public async Task<string> DecryptVote(string voteEncryptStr, string ballotPrivatekey, string voterkey)
    {
        var result1 = await jsInterop.InvokeAsync<string>("SRBB_decrypt_AES", voterkey, voteEncryptStr);

        var tmpstr2 = Convert.FromBase64String(result1);
        var result2 = await jsInterop.InvokeAsync<string>("SRBB_decrypt_RSA", ballotPrivatekey, tmpstr2);

        return result2;
    }
}


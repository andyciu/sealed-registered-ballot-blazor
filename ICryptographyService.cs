namespace sealed_registered_ballot_blazor;

public interface ICryptographyService
{
    Task<(string rsaPublicstr, string rsaPrivatestr)> GetRSAKeyPair();
    Task<string> GetAESKey();
    Dictionary<string, int> CreateVoterOptionDict(int optCount);
    Dictionary<string, int> CreateVoterOptionDict(string votestr);
    string ConvertVoterOptionDictToString(Dictionary<string, int> opts);
    Task<string> EncryptVote(string votestr, string ballotPublickey, string voterkey);
    Task<string> DecryptVote(string voteEncryptStr, string ballotPrivatekey, string voterkey);
}


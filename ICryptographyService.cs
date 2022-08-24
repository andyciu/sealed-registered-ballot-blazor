namespace sealed_registered_ballot_blazor;

public interface ICryptographyService
{
    Task<(string rsaPublicstr, string rsaPrivatestr)> GetRSAKeyPair();
    Task<string> GetAESKey();
    string CreateVoterString();
    Task<string> EncryptVote(string votestr, string ballotPublickey, string voterPublickey);
}


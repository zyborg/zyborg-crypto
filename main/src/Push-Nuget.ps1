$apikey = Get-Credential

dotnet pack $PSScriptRoot\Zyborg.Security.Cryptography
#dotnet pack $PSScriptRoot\Zyborg.Security.Cryptography.TrivialShamir
dotnet pack $PSScriptRoot\Zyborg.Security.Cryptography.HashiCorpShamir

dotnet nuget push -k $apikey.GetNetworkCredential().Password -s https://nuget.org/ $PSScriptRoot\Zyborg.Security.Cryptography\bin\Debug\
#dotnet nuget push -k $apikey.GetNetworkCredential().Password -s https://nuget.org/ $PSScriptRoot\Zyborg.Security.Cryptography.TrivialShamir\bin\Debug\
dotnet nuget push -k $apikey.GetNetworkCredential().Password -s https://nuget.org/ $PSScriptRoot\Zyborg.Security.Cryptography.HashiCorpShamir\bin\Debug\

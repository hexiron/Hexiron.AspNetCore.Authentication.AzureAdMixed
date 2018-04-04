param (
	[string]$BuildVersionNumber=$(throw "-BuildVersionNumber is required."),
	[string]$TagVersionNumber
)

if ($TagVersionNumber){
	Write-Host "TagVersion: $TagVersionNumber"
}
else{
	Write-Host "Version: $BuildVersionNumber"
}

Get-ChildItem -Path $PSScriptRoot\..\src -Filter *.csproj -Recurse | ForEach-Object{ 
    $ProjectJsonPath =  $_.FullName
	$csproj = [xml](Get-Content $ProjectJsonPath)
    if ($TagVersionNumber){
       $csproj.Project.PropertyGroup.VersionPrefix = $TagVersionNumber
	   $csproj.Save($ProjectJsonPath)
    }
    else{
       $csproj.Project.PropertyGroup.VersionPrefix = $BuildVersionNumber
	   $csproj.Save($ProjectJsonPath)
    }
}
dotnet build "$PSScriptRoot\Hexiron.AspNetCore.Authentication.AzureAdMixed.sln"
dotnet pack "$PSScriptRoot\src\Hexiron.AspNetCore.Authentication.AzureAdMixed\Hexiron.AspNetCore.Authentication.AzureAdMixed.csproj"
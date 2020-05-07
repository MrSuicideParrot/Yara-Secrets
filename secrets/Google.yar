rule Google_API_Key
{
    meta:
        description = "Google API Key"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /AIza[0-9A-Za-z\\-_]{35}/

    condition:
        $regex1
}

rule Google_Cloud_Platform_API_Key
{
    meta:
        description = "Google Cloud Platform API Key"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]/

    condition:
        $regex1
}

rule Google_Oauth
{
    meta:
        description = "Google Drive Oauth"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/

    condition:
        $regex1
}

rule Google_Oauth_Access_Token
{
    meta:
        description = "Google Oauth Access Token"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /ya29\\.[0-9A-Za-z\\-_]+/

    condition:
        $regex1
}
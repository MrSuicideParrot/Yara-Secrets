rule AWS_Manager_ID
{
    meta:
        description = "AWS Manager ID"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/ nocase

    condition:
        $regex1
}

rule AWS_cred_file
{
    meta:
        description = "AWS cred file info"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z\/+]{20,40}/ nocase

    condition:
        $regex1

}

rule AWS_Secret_Key
{
    meta:
        description = "AWS Secret Key"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]/ nocase

    condition:
        $regex1
}

rule AWS_MWS_Key
{
    meta:
        description = "AWS Secret Key"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ nocase

    condition:
        $regex1
}
rule Github
{
    meta:
        description = "Github"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}/ nocase

    condition:
        $regex1
}
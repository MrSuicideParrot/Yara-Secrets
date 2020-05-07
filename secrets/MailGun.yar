rule MailGun
{
    meta:
        description = "MailGun"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /key-[0-9a-zA-Z]{32}/

    condition:
        $regex1
}
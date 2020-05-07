rule MailChimp
{
    meta:
        description = "MailChimp"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /[0-9a-f]{32}-us[0-9]{1,2}/

    condition:
        $regex1
}
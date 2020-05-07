rule Twilio
{
    meta:
        description = "Twilio"
        author = "André Cirne"
        date = "2020-05-07"
        reference = "https://github.com/l4yton/RegHex"

    strings:
        $regex1 = /55[0-9a-fA-F]{32}/

    condition:
        $regex1
}
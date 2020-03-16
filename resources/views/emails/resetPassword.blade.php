<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Test Mail</title>
</head>
<body>
<p>Hi {{$firstName}},</p>
Forgot your password, huh? No big deal.<br />
To create a new password, just follow this link:<br /><br/>
<strong style="font: 16px/18px Arial, Helvetica, sans-serif;"><b><a href="{{$resetURL}}" style="color: #3366cc;">Create a new password</a></b></strong><br />
<br/>
Link doesn't work? Copy the following link to your browser address bar:<br />
<nobr><a href="{{$resetURL}}" style="color: #3366cc;">{{$resetURL}}</a></nobr>
<br /><br/>
You received this email, because it was requested by a <a href="https://www.uslawshield.com" style="color: #3366cc;">US LawShield</a> member.
This is part of the procedure to create a new password on the system. If you DID NOT request a new password then please
ignore this email and your password will remain the same.
<br /><br/>
Your password reset link will expire within 2 hours. Please change your password as soon as possible.
<br /><br/>
Thank you,<br />
The USLS Team
</body>
</html>

export const MailTemplates = {
  OTP: {
    SUBJECT: "Your verification code – Learn Vista",

    TEXT: (otp: string) => `
Your verification code is: ${otp}

This code will expire in 5 minutes.

If you did not request this, please ignore this email.

– Learn Vista Team
`,

    HTML: (otp: string) => `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>Verify your email</title>
  </head>
  <body style="margin:0; padding:0; background:#f5f5f5; font-family: Arial, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center" style="padding:40px 0;">
          <table width="420" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:8px; padding:32px;">
            <tr>
              <td style="text-align:center;">
                <h2 style="margin:0 0 16px 0; color:#111;">Verify your email</h2>
                <p style="margin:0 0 24px 0; color:#555;">
                  Use the code below to complete your registration.
                </p>

                <div style="font-size:32px; font-weight:700; letter-spacing:6px; color:#000; margin-bottom:24px;">
                  ${otp}
                </div>

                <p style="margin:0 0 16px 0; color:#777; font-size:14px;">
                  This code will expire in <strong>5 minutes</strong>.
                </p>

                <p style="margin:0; color:#999; font-size:12px;">
                  If you didn’t request this, you can safely ignore this email.
                </p>

                <hr style="margin:32px 0; border:none; border-top:1px solid #eee;" />

                <p style="margin:0; font-size:12px; color:#aaa;">
                  © Learn Vista
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
`,
  },

  PASSWORD_RESET: {
    SUBJECT: "Reset your password – Learn Vista",

    TEXT: (link: string) => `
You requested a password reset.

Reset your password using the link below:
${link}

This link will expire soon.

If you didn’t request this, ignore this email.

– Learn Vista Team
`,

    HTML: (link: string) => `
<!DOCTYPE html>
<html>
  <body style="margin:0; padding:0; background:#f5f5f5; font-family: Arial, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center" style="padding:40px 0;">
          <table width="420" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:8px; padding:32px;">
            <tr>
              <td style="text-align:center;">
                <h2 style="margin-bottom:16px;">Reset your password</h2>

                <p style="color:#555; margin-bottom:24px;">
                  Click the button below to reset your password.
                </p>

                <a href="${link}"
                   style="display:inline-block; padding:12px 24px; background:#000; color:#fff; text-decoration:none; border-radius:6px; font-weight:600;">
                  Reset Password
                </a>

                <p style="margin-top:24px; font-size:12px; color:#999;">
                  If you didn’t request this, you can ignore this email.
                </p>

                <hr style="margin:32px 0; border:none; border-top:1px solid #eee;" />

                <p style="font-size:12px; color:#aaa;">
                  © Learn Vista
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
`,
  },

  MENTOR_STATUS_CHANGE: {
    SUBJECT: "Mentor application update – Learn Vista",

    TEXT: (status: string) => `
Your mentor application status has been updated.

Current status: ${status}

– Learn Vista Team
`,

    HTML: (status: string) => `
<!DOCTYPE html>
<html>
  <body style="margin:0; padding:0; background:#f5f5f5; font-family: Arial, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center" style="padding:40px 0;">
          <table width="420" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:8px; padding:32px;">
            <tr>
              <td style="text-align:center;">
                <h2 style="margin-bottom:16px;">Mentor status update</h2>

                <p style="color:#555; margin-bottom:16px;">
                  Your mentor application status has changed.
                </p>

                <strong style="font-size:18px;">${status}</strong>

                <hr style="margin:32px 0; border:none; border-top:1px solid #eee;" />

                <p style="font-size:12px; color:#aaa;">
                  © Learn Vista
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
`,
  },
};

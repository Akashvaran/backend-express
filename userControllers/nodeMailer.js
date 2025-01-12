import nodemailer from "nodemailer";

const sendEmail = async (to, subject, htmlContent) => {
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS, 
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject,
        html: htmlContent,
    };

    return transporter.sendMail(mailOptions);
};
export default sendEmail
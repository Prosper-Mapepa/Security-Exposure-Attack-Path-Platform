export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface EmailAdapter {
  send(message: EmailMessage): Promise<void>;
}

export class ConsoleEmailAdapter implements EmailAdapter {
  async send(message: EmailMessage): Promise<void> {
    console.info(
      JSON.stringify({
        service: 'email',
        event: 'email.queued',
        to: message.to,
        subject: message.subject,
      }),
    );
  }
}

export class SmtpEmailAdapter implements EmailAdapter {
  constructor(private readonly url: string, private readonly from: string) {}

  async send(message: EmailMessage): Promise<void> {
    const nodemailer = await import('nodemailer');
    const transport = nodemailer.createTransport(this.url);
    await transport.sendMail({
      from: this.from,
      to: message.to,
      subject: message.subject,
      text: message.text,
    });
  }
}

export function createEmailAdapter(): EmailAdapter {
  if (process.env.EMAIL_PROVIDER === 'smtp' && process.env.SMTP_URL) {
    return new SmtpEmailAdapter(process.env.SMTP_URL, process.env.EMAIL_FROM ?? 'security@localhost');
  }
  return new ConsoleEmailAdapter();
}

export function ContactForm({ action }: { action: (data: FormData) => Promise<void> }) {
  return (
    <form action={action}>
      <label htmlFor="message">Message</label>
      <input id="message" name="message" type="text" required />
      <button type="submit">Send</button>
    </form>
  )
}

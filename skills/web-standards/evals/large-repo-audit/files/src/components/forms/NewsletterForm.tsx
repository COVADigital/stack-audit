export function NewsletterForm({ action }: { action: (data: FormData) => Promise<void> }) {
  return (
    <form action={action}>
      <input name="email" type="email" placeholder="you@example.com" required />
      <button type="submit">Subscribe</button>
    </form>
  )
}

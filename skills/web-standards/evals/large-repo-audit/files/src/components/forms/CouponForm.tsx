export function CouponForm({ action }: { action: (data: FormData) => Promise<void> }) {
  return (
    <form action={action}>
      <label htmlFor="code">Code</label>
      <input id="code" name="code" type="text" required />
      <button type="submit">Send</button>
    </form>
  )
}

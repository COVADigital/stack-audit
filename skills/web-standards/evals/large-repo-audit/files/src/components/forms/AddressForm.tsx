export function AddressForm({ action }: { action: (data: FormData) => Promise<void> }) {
  return (
    <form action={action}>
      <label htmlFor="street">Street</label>
      <input id="street" name="street" type="text" required />
      <button type="submit">Send</button>
    </form>
  )
}

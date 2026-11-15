type Props = { title: string; note?: string }

export function Promo2({ title, note }: Props) {
  return (
    <section aria-labelledby="promo2-title">
      <h2 id="promo2-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

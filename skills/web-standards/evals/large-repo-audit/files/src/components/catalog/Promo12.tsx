type Props = { title: string; note?: string }

export function Promo12({ title, note }: Props) {
  return (
    <section aria-labelledby="promo12-title">
      <h2 id="promo12-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

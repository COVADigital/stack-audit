type Props = { title: string; note?: string }

export function Stock6({ title, note }: Props) {
  return (
    <section aria-labelledby="stock6-title">
      <h2 id="stock6-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

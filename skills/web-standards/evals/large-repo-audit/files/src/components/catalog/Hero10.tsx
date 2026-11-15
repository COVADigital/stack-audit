type Props = { title: string; note?: string }

export function Hero10({ title, note }: Props) {
  return (
    <section aria-labelledby="hero10-title">
      <h2 id="hero10-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

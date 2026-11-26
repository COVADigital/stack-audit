type Props = { title: string; note?: string }

export function Banner1({ title, note }: Props) {
  return (
    <section aria-labelledby="banner1-title">
      <h2 id="banner1-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

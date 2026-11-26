type Props = { title: string; note?: string }

export function Price14({ title, note }: Props) {
  return (
    <section aria-labelledby="price14-title">
      <h2 id="price14-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

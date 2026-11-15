type Props = { title: string; note?: string }

export function Badge13({ title, note }: Props) {
  return (
    <section aria-labelledby="badge13-title">
      <h2 id="badge13-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

type Props = { title: string; note?: string }

export function Badge3({ title, note }: Props) {
  return (
    <section aria-labelledby="badge3-title">
      <h2 id="badge3-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

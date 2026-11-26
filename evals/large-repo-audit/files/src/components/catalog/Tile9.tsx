type Props = { title: string; note?: string }

export function Tile9({ title, note }: Props) {
  return (
    <section aria-labelledby="tile9-title">
      <h2 id="tile9-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

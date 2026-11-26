type Props = { title: string; note?: string }

export function Swatch7({ title, note }: Props) {
  return (
    <section aria-labelledby="swatch7-title">
      <h2 id="swatch7-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

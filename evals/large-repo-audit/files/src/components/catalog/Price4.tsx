type Props = { title: string; note?: string }

export function Price4({ title, note }: Props) {
  return (
    <section aria-labelledby="price4-title">
      <h2 id="price4-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

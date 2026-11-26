type Props = { title: string; note?: string }

export function Banner11({ title, note }: Props) {
  return (
    <section aria-labelledby="banner11-title">
      <h2 id="banner11-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

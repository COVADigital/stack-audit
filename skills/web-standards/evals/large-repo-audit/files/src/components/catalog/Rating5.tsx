type Props = { title: string; note?: string }

export function Rating5({ title, note }: Props) {
  return (
    <section aria-labelledby="rating5-title">
      <h2 id="rating5-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

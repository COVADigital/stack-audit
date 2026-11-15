type Props = { title: string; note?: string }

export function Chip8({ title, note }: Props) {
  return (
    <section aria-labelledby="chip8-title">
      <h2 id="chip8-title">{title}</h2>
      {note ? <p>{note}</p> : null}
    </section>
  )
}

type Props = { src: string; label: string }

export function Thumb23({ src, label }: Props) {
  return (
    <figure>
      <img src={src} width={160} height={160} loading="lazy" />
      <figcaption>{label}</figcaption>
    </figure>
  )
}

type Props = { src: string; label: string }

export function Thumb21({ src, label }: Props) {
  return (
    <figure>
      <img src={src} alt={label} width={160} height={160} loading="lazy" />
      <figcaption>{label}</figcaption>
    </figure>
  )
}

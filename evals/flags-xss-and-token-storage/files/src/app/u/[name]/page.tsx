import { getUser } from '@/lib/db'

export default async function Profile({ params }: { params: Promise<{ name: string }> }) {
  const { name } = await params
  const user = await getUser(name)
  return (
    <main>
      <h1>{user.name}</h1>
      <div dangerouslySetInnerHTML={{ __html: user.bio }} />
    </main>
  )
}

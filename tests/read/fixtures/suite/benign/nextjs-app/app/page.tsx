import { z } from "zod";

const Props = z.object({ title: z.string(), items: z.array(z.string()) });

export default async function Page({ searchParams }: { searchParams: unknown }) {
  const { title, items } = Props.parse(searchParams);
  return (
    <main>
      <h1>{title}</h1>
      <ul>{items.map((i) => <li key={i}>{i}</li>)}</ul>
    </main>
  );
}

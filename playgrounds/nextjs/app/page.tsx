export default function Home() {
  return (
    <main
      className="
        bg-blue-500 min-h-screen w-screen p-12 text-white-800
        lg(p-45)
        mesh([slate-100, sky-200], [slate-300, blue-300])
        dark(mesh([slate-800, blue-900], [slate-900, purple-900]) text-gray-200)
        animate:2s from(opacity-0) to(opacity-100) forwards
      "
    >
      <div className="max-w-5xl mx-auto">

        <div className="card(p-13 bg-black/50 backdrop-blur-lg rounded-xl shadow-lg) dark(bg-black/50) div(h1(font-bold) p(mt-2))">

          <h1 className="text-4xl md:text-5xl ~text(2rem@md, 3rem@xl)">
            Dx Styles Grouping
          </h1>

          <p className="text-lg text-gray-600 dark(text-gray-400)">
            This page is a showcase of all 13 new Grouping features.
          </p>
        </div>

        <div className="+card(mt-8)">
          <h2 className="text-2xl font-bold mb-4">Container & Conditional Queries</h2>
          <div className="container-type-inline-size resize-x overflow-auto border-2 border-dashed border-gray-400 p-4 w-full min-w-[250px] max-w-full">

            <div
              className="
                p-6 rounded-lg bg-blue-200 text-blue-900 
                _highlight(bg-yellow-200 text-yellow-900)
                ?@container>640px(bg-green-200 text-green-900)
                ?@self:child-count>2(_highlight)
                transition(300ms)
              "
            >
              <p className="font-bold text-lg ?@container>640px(text-xl)">
                I change based on my container!
              </p>
              <p className="mt-2">Try resizing my parent container.</p>
            </div>
          </div>
        </div>

        <div className="+card(mt-8) div(div(mt-4))">
          <h2 className="text-2xl font-bold mb-4">Interactive Features</h2>

          <div>
            <h3 className="font-semibold">State Modifiers & Data Attributes</h3>
            <button
              className="
                p-4 rounded-lg bg-blue-500 text-white font-bold
                hover(bg-blue-600 shadow-lg)
                focus(outline-none ring-4 ring-blue-300)
                *loading(bg-gray-400 animate-pulse cursor-wait)
              "
            >
              Hover, Focus, or Add [data-loading]
            </button>
          </div>

          <div>
            <h3 className="font-semibold">Physics Motion</h3>
            <div className="
              p-10 bg-purple-500 text-white rounded-lg w-32 text-center
              transition(500ms)
              hover(scale-110 rotate-[-5deg])
              motion(mass:1 stiffness:180 damping:12)
            ">
              Bouncy!
            </div>
          </div>

          <div>
            <h3 className="font-semibold">Generated Utilities</h3>
            <div className="$focus-ring(outline-none ring-4 ring-offset-2 ring-purple-500)"></div>
            <input
              type="text"
              placeholder="Focus me"
              className="p-20 border rounded-lg focus($focus-ring)"
            />
          </div>
        </div>
      </div>
    </main>
  );
}

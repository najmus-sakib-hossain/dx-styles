export default function Home() {
  return (
    <main
      className="
        min-h-screen w-screen
        p-4 md:p-8
        text-gray-800
        
        // Feature 8: Gradients
        mesh([slate-100, sky-200], [slate-300, blue-300])
        
        // Feature 6: Theming
        dark(mesh([slate-800, blue-900], [slate-900, purple-900]) text-gray-200)

        // Feature 5: Animation Keyframes
        animate:1s from(opacity-0) to(opacity-100) forwards
      "
    >
      <div className="max-w-5xl mx-auto">
        
        {/* Feature 1: Components (Defined here)
          Feature 4: Child Selectors
        */}
        <div className="card(p-8 bg-white/50 backdrop-blur-lg rounded-xl shadow-lg) dark(bg-black/50) div(h1(font-bold) p(mt-2))">
          
          {/* Feature 10: Fluid Scaling */}
          <h1 className="text-4xl md:text-5xl ~text(2.25rem@md, 3rem@xl)">
            Dx Styles Grouping
          </h1>

          <p className="text-lg text-gray-600 dark(text-gray-400)">
            This page is a showcase of all the new Grouping features.
          </p>
        </div>

        {/* --- Container & Conditional Queries Showcase --- */}
        <div className="+card(mt-8)">
          <h2 className="text-2xl font-bold mb-4">Container & Conditional Queries</h2>
          <div className="container-type-inline-size resize-x overflow-auto border-2 border-dashed border-gray-400 p-4 w-full min-w-[250px] max-w-full">
            
            {/* Feature 3: Responsive Modifiers (Container Queries)
              Feature 12: Conditional Queries
              Feature 9: Scoped Components
            */}
            <div
              className="
                p-6 rounded-lg 
                bg-blue-200 text-blue-900 
                
                // Defines a component only available in this scope
                _highlight(bg-yellow-200 text-yellow-900)

                // Applies styles when the container is > 640px wide
                ?@container>640px(bg-green-200 text-green-900)
                
                // Applies styles when the container has more than 2 children
                ?@self:child-count>2(_highlight)

                transition-all duration-300
              "
            >
              <p className="font-bold text-lg ?@container>640px(text-xl)">
                I change based on my container!
              </p>
              <p className="mt-2">Try resizing my parent container.</p>
              {/* Uncomment the line below to trigger the child-count query */}
              {/* <p className="mt-2">I am the third child!</p> */}
            </div>
          </div>
        </div>

        {/* --- Interactive Showcase --- */}
        <div className="+card(mt-8) div(div(mt-4))">
          <h2 className="text-2xl font-bold mb-4">Interactive Features</h2>
          
          <div>
            <h3 className="font-semibold">State Modifiers & Data Attributes</h3>
            {/* Feature 2: State Modifiers
              Feature 7: Data Attributes
            */}
            <button 
              className="
                p-4 rounded-lg bg-blue-500 text-white font-bold
                hover(bg-blue-600 shadow-lg)
                focus(outline-none ring-4 ring-blue-300)
                *loading(bg-gray-400 animate-pulse cursor-wait)
              "
              // Add data-loading attribute in DevTools to see the effect
            >
              Hover, Focus, or Add [data-loading]
            </button>
          </div>

          <div>
            <h3 className="font-semibold">Physics Motion</h3>
            {/* Feature 11: Physics Motion */}
            <div className="
              p-6 bg-purple-500 text-white rounded-lg w-32 text-center
              transition(500ms)
              hover(scale-110 rotate-[-5deg])
              motion(mass:1 stiffness:180 damping:12)
            ">
              Bouncy!
            </div>
          </div>

          <div>
            <h3 className="font-semibold">Generated Utilities</h3>
            {/* Feature 13: Generated Utility */}
            <div className="$focus-ring(outline-none ring-4 ring-offset-2 ring-purple-500)"></div>
            <input 
              type="text" 
              placeholder="Focus me" 
              className="p-4 border rounded-lg focus($focus-ring)"
            />
          </div>

        </div>
      </div>
    </main>
  );
}

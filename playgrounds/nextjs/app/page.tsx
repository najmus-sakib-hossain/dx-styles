export default function Home() {
  return (
    <main className="p-4 md:p-8 bg-gray-50 min-h-screen text-gray-800">
      <div className="max-w-5xl mx-auto">
        <h1 className="text-4xl md:text-5xl font-bold">
          Dx Styles Container Queries
        </h1>
        <p className="hover:mt-5 text-lg text-gray-600">
          Resize the container below by dragging its bottom-right corner. The
          inner element will change its background color and text size based on
          the container's width, not the viewport's width.
        </p>

        <div className="mt-8">
          <div className="container-type-inline-size resize-x overflow-auto border-2 border-dashed border-gray-400 p-4 w-full min-w-[250px] max-w-full">
            <div
              className="
                p-6 rounded-lg 
                bg-blue-300 text-blue-900 
                @sm:bg-green-300 @sm:text-green-900
                @lg:bg-yellow-300 @lg:text-yellow-900
                @2xl:bg-red-300 @2xl:text-red-900
                transition-all duration-300
              "
            >
              <p
                className="
                  font-bold 
                  text-lg 
                  @sm:text-xl 
                  @lg:text-2xl 
                  @2xl:text-3xl
                "
              >
                I change based on my container!
              </p>
              <p className="mt-2">Try resizing my parent container.</p>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

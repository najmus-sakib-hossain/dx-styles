1. CSS Transition Properties
These properties control how an element smoothly changes from one state to another.

transition

Description: A shorthand property to set all the individual transition properties in a single line.

Example: transition: background-color 1s ease-in-out 0.5s;

transition-property

Description: Specifies the name of the CSS property to which the transition effect is applied.

Example: transition-property: width;

transition-duration

Description: Defines how long the transition animation should take to complete.

Example: transition-duration: 2s;

transition-timing-function

Description: Specifies the speed curve of the transition effect (e.g., starting slow and speeding up).

Example: transition-timing-function: ease-in-out;

transition-delay

Description: Specifies a delay (in seconds or milliseconds) before the transition effect begins.

Example: transition-delay: 1s;

2. CSS Animation Properties
These properties control the more complex, keyframe-based animations.

animation

Description: A shorthand property to set all the individual animation properties in a single line.

Example: animation: slide-in 2s ease-in infinite alternate;

animation-name

Description: Specifies the name of the @keyframes rule that defines the animation.

Example: animation-name: my-cool-animation;

animation-duration

Description: Defines how long one cycle of the animation should take to complete.

Example: animation-duration: 3s;

animation-timing-function

Description: Specifies the speed curve of the animation.

Example: animation-timing-function: linear;

animation-delay

Description: Specifies a delay before the animation starts.

Example: animation-delay: 500ms;

animation-iteration-count

Description: Specifies the number of times the animation cycle should be played.

Example: animation-iteration-count: infinite;

animation-direction

Description: Defines whether the animation should play forwards, backwards, or alternate between the two.

Example: animation-direction: alternate-reverse;

animation-fill-mode

Description: Sets the style applied to the element before the animation starts and after it ends.

Example: animation-fill-mode: forwards;

animation-play-state

Description: Specifies whether the animation is currently running or paused.

Example: animation-play-state: paused;

3. The @keyframes At-Rule
This rule defines the stages and styles of the animation sequence.

from

Description: The starting point of the animation (equivalent to 0%).

Example: from { opacity: 0; }

to

Description: The ending point of the animation (equivalent to 100%).

Example: to { opacity: 1; }

<percentage>

Description: A specific point in the animation's timeline, from 0% to 100%.

Example: 50% { transform: scale(1.2); }

4. CSS Transform Properties
These properties relate to applying transformations to an element.

transform

Description: Applies a 2D or 3D transformation to an element using one or more transform functions.

Example: transform: rotate(45deg) scale(1.5);

transform-origin

Description: Sets the origin point (the "center") for an element's transformations.

Example: transform-origin: top left;

transform-style

Description: Specifies how nested elements are rendered in 3D space. preserve-3d allows them to maintain their 3D position.

Example: transform-style: preserve-3d;

perspective

Description: Gives a 3D-positioned element a sense of depth. This is applied to the parent container.

Example: perspective: 1000px;

backface-visibility

Description: Defines if the back face of a rotated element should be visible or hidden.

Example: backface-visibility: hidden;

5. CSS Transform Functions (Values for the transform property)
2D Transform Functions
translate(x, y) - Moves the element horizontally and vertically.

translateX(x) - Moves the element horizontally.

translateY(y) - Moves the element vertically.

scale(x, y) - Resizes the element's width and height.

scaleX(x) - Resizes the element's width.

scaleY(y) - Resizes the element's height.

rotate(angle) - Rotates the element clockwise.

skew(x-angle, y-angle) - Skews the element along its X and Y axes.

skewX(angle) - Skews the element along its X-axis.

skewY(angle) - Skews the element along its Y-axis.

3D Transform Functions
translate3d(x, y, z) - Moves an element in 3D space.

translateZ(z) - Moves the element along the Z-axis.

scale3d(x, y, z) - Resizes an element in 3D space.

scaleZ(z) - Resizes the element along the Z-axis.

rotate3d(x, y, z, angle) - Rotates an element around a specific 3D vector.

rotateX(angle) - Rotates the element around its X-axis.

rotateY(angle) - Rotates the element around its Y-axis.

rotateZ(angle) - Rotates the element around its Z-axis.

perspective(n) - Defines the perspective for a transformed element.
const bg=document.getElementById("bg");

let t=0;

function animate(){

t+=0.003;

const x=50+Math.sin(t)*10;
const y=50+Math.cos(t*1.3)*10;

bg.style.background=
`radial-gradient(circle at ${x}% ${y}%, #0f4c81 0%, #07111f 45%, #040913 100%)`;

requestAnimationFrame(animate);

}

animate();

document.querySelectorAll(".btn").forEach(btn=>{

btn.addEventListener("mouseenter",()=>{

btn.style.transform="translateY(-3px) scale(1.03)";

});

btn.addEventListener("mouseleave",()=>{

btn.style.transform="translateY(0) scale(1)";

});

});

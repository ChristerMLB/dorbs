import * as THREE from "./three.module.min.js";

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(
  75,
  600 / 400,
  0.1,
  1000
);

const renderer = new THREE.WebGLRenderer({ alpha: true });
renderer.setSize(600, 400);
renderer.setClearColor(0x000000, 0);
document.getElementById("threedee").appendChild(renderer.domElement);

const geometry = new THREE.BoxGeometry();
const material = new THREE.MeshBasicMaterial({ color: 0xca1800 });
const cube = new THREE.Mesh(geometry, material);
scene.add(cube);

camera.position.z = 2;

function animate() {
  requestAnimationFrame(animate);

  cube.rotation.x += 0.01;
  cube.rotation.y += 0.01;

  renderer.render(scene, camera);
}
animate();
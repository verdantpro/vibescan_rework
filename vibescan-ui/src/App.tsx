import { Route, Routes } from "react-router-dom";
import TopBar from "./components/TopBar";
import Console from "./pages/Console";
import Feed from "./pages/Feed";
import Search from "./pages/Search";
import Stats from "./pages/Stats";
import Signal from "./pages/Signal";

export default function App() {
  return (
    <>
      <TopBar />
      <main>
        <Routes>
          <Route path="/" element={<Console />} />
          <Route path="/feed" element={<Feed />} />
          <Route path="/search" element={<Search />} />
          <Route path="/stats" element={<Stats />} />
          <Route path="/signal/:ip/:port" element={<Signal />} />
        </Routes>
      </main>
    </>
  );
}

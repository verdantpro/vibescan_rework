import { Route, Routes } from "react-router-dom";
import TopBar from "./components/TopBar";
import Footer from "./components/Footer";
import Console from "./pages/Console";
import Feed from "./pages/Feed";
import Search from "./pages/Search";
import Stats from "./pages/Stats";
import Signal from "./pages/Signal";
import About from "./pages/About";
import NotFound from "./pages/NotFound";

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
          <Route path="/about" element={<About />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
      <Footer />
    </>
  );
}


class Directory:
    def __init__(self, parent):
        self.parent = parent
        self.sub_directories={}
        self.records={}

class PathHierarchy:
    def __init__(self, db, cur_path=""):
        self.db = db
        self.cur_dir, self.cur_leaf = self.split_path(cur_path)

        self.update_hierarchy()

    @staticmethod
    def split_path(path):
        path_split = path.split("/")
        dirs, leaf = path_split[:-1], path_split[-1]
        return dirs, leaf

    def listdir(self):
        d = self.get_subdirectory(self.cur_dir)
        return d.sub_directories.keys(), d.records.keys()

    def get_subdirectory(self, dirs):
        dir_iter = self.root
        for d in dirs:
            if not d in dir_iter.sub_directories:
                dir_iter.sub_directories[d] = Directory(dir_iter)
            dir_iter = dir_iter.sub_directories[d]
        return dir_iter

    def update_hierarchy(self):
        self.root = Directory(None)

        for path in self.db.records.keys():
            dirs, leaf = self.split_path(path)
            cur_dir = self.get_subdirectory(dirs)
            cur_dir.records[leaf] = path

    def chdir(self, path):
        if path == "":
            self.cur_dir = [],
            self.cur_leaf = ""
        else:
            self.cur_leaf = ""
            for part in path.split("/"):
                if part=="..":
                    is_dir=True
                    if len(self.cur_dir)>0:
                        self.cur_dir.pop()
                elif part=="":
                    is_dir = True
                else:
                    is_dir=False
                    self.cur_dir.append(part)
            if not is_dir:
                # Interpret it as a leaf if there is a leaf or no folder
                alt_dir, alt_leaf = self.cur_dir[:-1], self.cur_dir[-1]
                alt_subdir = self.get_subdirectory(alt_dir)
                if (alt_leaf in alt_subdir.records) or not (alt_leaf in alt_subdir.sub_directories):
                    self.cur_dir, self.cur_leaf = alt_dir, alt_leaf
        return "/".join(self.cur_dir+[self.cur_leaf])
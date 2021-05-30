

class Directory:
    def __init__(self, parent):
        self.parent = parent
        self.subdirs={}
        self.records={}

    def print(self, prefix):
        for idx, (name, subdir) in enumerate(self.subdirs.items()):
            last = (idx == len(self.subdirs)-1) and len(self.records)==0
            if last:
                boxchar_self = "╰─┬"
                boxchar_children = "  "
            else:
                boxchar_self = "├─┬"
                boxchar_children = "│ "

            print(f"{prefix}{boxchar_self} {name}/")
            subdir.print(prefix+boxchar_children)
        for idx, name in enumerate(self.records.keys()):
            if idx==len(self.records)-1:
                boxchar="╰──"
            else:
                boxchar="├──"
            print(f"{prefix}{boxchar} {name}")

class PathHierarchy:
    def __init__(self, db, searchterm=""):
        self.db = db
        self.searchterm = searchterm

        self.update_hierarchy()

    def update_hierarchy(self):
        self.root = Directory(None)

        for path in self.db.records.keys():
            if self.searchterm and path.find(self.searchterm)<0:
                continue
            dirs, leaf = self.split_path(path)
            cur_dir = self.get_subdirectory(dirs)
            cur_dir.records[leaf] = path

    @staticmethod
    def split_path(path):
        path_split = path.split("/")
        dirs, leaf = path_split[:-1], path_split[-1]
        return list(dirs), leaf

    def print(self):
        print("╮")
        self.root.print("")


    def get_subdirectory(self, dirs):
        dir_iter = self.root
        for d in dirs:
            if not d in dir_iter.subdirs:
                dir_iter.subdirs[d] = Directory(dir_iter)
            dir_iter = dir_iter.subdirs[d]
        return dir_iter

    def tab_complete(self, prefix):
        matches=[]
        for path in self.db.records.keys():
            if path.startswith(prefix):
                matches.append(path)
        return  matches

#class Directory:
#    def __init__(self, parent):
#        self.parent = parent
#        self.subdirs={}
#        self.records={}
#
#class PathHierarchy:
#    def __init__(self, db, cur_path=""):
#        self.db = db
#        self.cur_dir, self.cur_leaf = self.split_path(cur_path)
#
#        self.update_hierarchy()
#
#    @staticmethod
#    def split_path(path):
#        path_split = path.split("/")
#        dirs, leaf = path_split[:-1], path_split[-1]
#        return list(dirs), leaf
#
#    def listdir(self):
#        d = self.get_subdirectory(self.cur_dir)
#        return d.subdirs.keys(), d.records.keys()
#
#
#    def update_hierarchy(self):
#        self.root = Directory(None)
#
#        for path in self.db.records.keys():
#            dirs, leaf = self.split_path(path)
#            cur_dir = self.get_subdirectory(dirs)
#            cur_dir.records[leaf] = path
#
#    def chdir(self, path):
#        if path == "":
#            self.cur_dir = []
#            self.cur_leaf = ""
#        else:
#            self.cur_leaf = ""
#            for part in path.split("/"):
#                if part=="..":
#                    is_dir=True
#                    if len(self.cur_dir)>0:
#                        self.cur_dir.pop()
#                elif part=="":
#                    is_dir = True
#                else:
#                    is_dir=False
#                    self.cur_dir.append(part)
#            if not is_dir:
#                # Interpret it as a leaf if there is a leaf or no folder
#                alt_dir, alt_leaf = self.cur_dir[:-1], self.cur_dir[-1]
#                alt_subdir = self.get_subdirectory(alt_dir)
#                if (alt_leaf in alt_subdir.records) or not (alt_leaf in alt_subdir.subdirs):
#                    self.cur_dir, self.cur_leaf = alt_dir, alt_leaf
#        return "/".join(self.cur_dir+[self.cur_leaf])